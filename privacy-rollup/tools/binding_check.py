#!/usr/bin/env python3
"""Check the covenant's transaction binding on a jmoik/bitcoin `gsr` regtest node, without a receipt.

The settlement leaf is `decls || <old_root> 1 CSV DROP || prologue || verifier`. The verifier part needs a proof
bound to the spending transaction; this check replaces it with `<journal digest from the witness> EQUALVERIFY`,
keeping the real declarations (so the root sits at the real `decl_len` offset), the real head and the real prologue.
A spend therefore succeeds exactly when

  * the index, shape (NUMS, single leaf) and successor-leaf checks pass, and
  * the journal digest the Script rebuilds with OP_TX equals the one computed here from the transaction,

which is what an `apply_batch` receipt is bound to. Negative spends must fail. Annex-bearing spends are nonstandard,
so the node runs with -acceptnonstdtxn=1 (moving batch data out of the annex is a separate step).

    python3 tools/binding_check.py      # writes build/binding-check.json
"""
import hashlib
import json
import shutil
import struct
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import rollup_covenant as rc  # noqa: E402
from rollup_covenant import (CScript, COutPoint, CTransaction, CTxIn, CTxInWitness, CTxOut,  # noqa: E402
                             V, taproot_construct)
from gsr import Asm  # noqa: E402

REPO = rc.REPO
BITCOIN = REPO / "build/bitcoin/bin"
BUILD = REPO / "build"
WORK = BUILD / "binding-check"
DATADIR = WORK / "regtest"
PORT = 28643
TEMPLATE = REPO / "privacy-rollup/fixtures/apply-batch/receipt-template.json"
OP_TRUE_SPK = bytes.fromhex("51")  # bare OP_TRUE is nonstandard but fine with -acceptnonstdtxn
FEE = 20_000


def sha(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def varbytes(b: bytes) -> bytes:
    from gsr import compact
    return compact(len(b)) + b


def rpc(method: str, *args):
    cmd = [str(BITCOIN / "bitcoin-cli"), "-regtest", f"-datadir={DATADIR}", f"-rpcport={PORT}", "-stdin", method]
    out = subprocess.run(cmd, input="\n".join(json.dumps(a) if not isinstance(a, str) else a for a in args),
                         capture_output=True, text=True)
    if out.returncode:
        raise RuntimeError(out.stderr.strip())
    try:
        return json.loads(out.stdout)
    except json.JSONDecodeError:
        return out.stdout.strip()


class TestLeaf:
    """The real declarations, head and prologue, then a journal-digest check instead of the verifier."""

    def __init__(self, cov: rc.Covenant, rollup_id: bytes, root: bytes) -> None:
        stmt = rc.RollupStatement(json.loads(TEMPLATE.read_text()), rollup_id, root)
        stmt.decl_len = cov.decl_len
        V.serial = 0
        jd_w, new = V("jd_w"), V("new_root")
        old = V("old_root")
        m = Asm([jd_w, new, old])
        stmt.prologue(m, {"new_root": new}, [old])
        m.roll(stmt.journal_digest(m))
        m.roll(jd_w)
        m.op("EQUALVERIFY", 2)
        m.drop_top(len(m.st))
        # The prologue's CompactSize prefix width (5) assumes a script of at least 64 KiB, as the real one is.
        m.s.data(bytes(60_000)).op("DROP")
        m.s.int(1)
        decls = cov.script[:cov.decl_len]
        self.script = decls + bytes(stmt.head().code) + bytes(m.s.code)
        self.decl_len, self.root = cov.decl_len, root
        assert self.script[self.decl_len:self.decl_len + 33] == b"\x20" + root
        tr = taproot_construct(rc.NUMS, [("rollup", CScript(self.script), rc.LEAF)])
        self.spk = bytes(tr.scriptPubKey)
        self.control = bytes([rc.LEAF | tr.negflag]) + rc.NUMS

    def for_root(self, root: bytes) -> "TestLeaf":
        other = object.__new__(TestLeaf)
        d = self.decl_len
        other.script = self.script[:d] + b"\x20" + root + self.script[d + 33:]
        other.decl_len, other.root = d, root
        tr = taproot_construct(rc.NUMS, [("rollup", CScript(other.script), rc.LEAF)])
        other.spk, other.control = bytes(tr.scriptPubKey), bytes([rc.LEAF | tr.negflag]) + rc.NUMS
        return other


def journal_digest(tx: CTransaction, spent: list[tuple[int, bytes]], rollup_id: bytes, old: bytes, new: bytes,
                   annex: bytes) -> bytes:
    """The 196-byte BatchJournal of state-transition, from the transaction (independent of the Script)."""
    ins = struct.pack("<iI", tx.version, tx.nLockTime)
    for txin, (amount, spk) in zip(tx.vin, spent):
        ins += txin.prevout.hash.to_bytes(32, "little") + struct.pack("<IQ", txin.prevout.n, amount)
        ins += varbytes(spk) + varbytes(txin.scriptSig) + struct.pack("<I", txin.nSequence)
    outs = b"".join(struct.pack("<q", o.nValue) + varbytes(bytes(o.scriptPubKey)) for o in tx.vout)
    journal = struct.pack("<I", 1) + rollup_id + old + new + sha(ins) + sha(outs) + sha(annex)
    assert len(journal) == 196
    return sha(journal)


def main() -> None:
    template = json.loads(TEMPLATE.read_text())
    rollup_id, root0, root1 = sha(b"binding-check rollup"), sha(b"root 0"), sha(b"root 1")
    t = time.time()
    cov = rc.Covenant(template, rollup_id, root0)
    gen_s = time.time() - t
    leaf0 = TestLeaf(cov, rollup_id, root0)
    leaf1 = leaf0.for_root(root1)
    # The real covenant's successor for root1 and the test leaf's share the splice code path.
    assert cov.for_root(root1).script[:cov.decl_len] == cov.script[:cov.decl_len]

    shutil.rmtree(DATADIR, ignore_errors=True)
    DATADIR.mkdir(parents=True)
    subprocess.run([str(BITCOIN / "bitcoind"), "-regtest", f"-datadir={DATADIR}", "-daemonwait", "-server",
                    "-listen=0", f"-rpcport={PORT}", f"-port={PORT + 1}", "-acceptnonstdtxn=1",
                    "-vbparams=tapleaf_0xc2:0:3999999999", "-fallbackfee=0.0001"], check=True)
    results: dict = {"covenant_bytes": len(cov.script), "decl_len": cov.decl_len, "generation_s": round(gen_s, 1),
                     "test_leaf_bytes": len(leaf0.script)}
    try:
        desc = rpc("getdescriptorinfo", "raw(51)")["descriptor"]
        rpc("generatetodescriptor", 101, desc)
        while rpc("getdeploymentinfo")["deployments"]["tapleaf_0xc2"].get("bip9", {}).get("status") != "active":
            rpc("generatetodescriptor", 144, desc)
        results["activation_height"] = rpc("getblockcount")
        cb_hash = rpc("getblockhash", 1)
        cb = rpc("getblock", cb_hash, 2)["tx"][0]
        cb_value = round(cb["vout"][0]["value"] * 100_000_000)

        # Fund the test covenant (value V0) from the OP_TRUE coinbase.
        v0 = 1_000_000
        fund = CTransaction()
        fund.version = 2
        fund.vin = [CTxIn(COutPoint(int(cb["txid"], 16), 0), b"", 0xFFFFFFFF)]
        fund.vout = [CTxOut(v0, CScript(leaf0.spk)), CTxOut(cb_value - v0 - FEE, CScript(OP_TRUE_SPK))]
        fund_txid = rpc("sendrawtransaction", fund.serialize().hex())
        rpc("generatetodescriptor", 1, desc)
        results["fund_txid"] = fund_txid

        def spend(new_leaf: TestLeaf, annex: bytes, *, out0_spk=None, jd_override=None, seq=1, new_root=None):
            tx = CTransaction()
            tx.version = 2
            tx.vin = [CTxIn(COutPoint(int(fund_txid, 16), 0), b"", seq),
                      CTxIn(COutPoint(int(fund_txid, 16), 1), b"", 0xFFFFFFFF)]
            tx.vout = [CTxOut(v0, CScript(out0_spk or new_leaf.spk)),
                       CTxOut(cb_value - v0 - 2 * FEE, CScript(OP_TRUE_SPK))]
            spent = [(v0, leaf0.spk), (cb_value - v0 - FEE, OP_TRUE_SPK)]
            nr = new_root or new_leaf.root
            jd = jd_override or journal_digest(tx, spent, rollup_id, root0, nr, annex)
            tx.wit.vtxinwit = [CTxInWitness(), CTxInWitness()]
            tx.wit.vtxinwit[0].scriptWitness.stack = [jd, nr, leaf0.script, leaf0.control] + ([annex] if annex else [])
            return tx

        annex = b"\x50\x00" + b"GSRP\x01" + root0 + root1 + b"batch body"
        good = spend(leaf1, annex)
        cases = {
            "wrong_journal_digest": spend(leaf1, annex, jd_override=sha(b"wrong")),
            "redirected_successor": spend(leaf1, annex, out0_spk=leaf0.for_root(sha(b"other")).spk),
            "successor_not_matching_new_root": spend(leaf1, annex, new_root=sha(b"other")),
            "sequence_0_fails_csv": spend(leaf1, annex, seq=0),
        }
        r = {}
        for name, tx in cases.items():
            acc = rpc("testmempoolaccept", [tx.serialize().hex()])[0]
            r[name] = {"allowed": acc["allowed"], "reject": acc.get("reject-reason")}
        acc = rpc("testmempoolaccept", [good.serialize().hex()])[0]
        r["good"] = {"allowed": acc["allowed"], "reject": acc.get("reject-reason"), "weight": good.get_weight()}
        if acc["allowed"]:
            r["good"]["txid"] = rpc("sendrawtransaction", good.serialize().hex(), 0)
            block = rpc("generatetodescriptor", 1, desc)[0]
            r["good"]["mined"] = r["good"]["txid"] in rpc("getblock", block, 1)["tx"]
        results["spends"] = r
        results["ok"] = r["good"]["allowed"] and not any(r[k]["allowed"] for k in cases)
    finally:
        try:
            rpc("stop")
        except RuntimeError:
            pass
    out = BUILD / "binding-check.json"
    out.write_text(json.dumps(results, indent=1))
    print(json.dumps(results, indent=1))


if __name__ == "__main__":
    main()
